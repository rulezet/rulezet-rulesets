rule PUP_AdvancedIPScanner_strings {
  meta:
    description   = "Matches strings found in the Advanced IP Scanner installer, often abused by malicious actors."
    last_modified = "2024-03-10"
    author        = "@petermstewart"
    DaysofYara    = "70/100"
    sha256        = "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b"

  strings:
    $a1 = "This installer contains the logic and data to install Advanced IP Scanner"
    $a2 = "www.advanced-ip-scanner.com/link.php?"
    $a3 = "advanced ip scanner; install; network scan; ip scan; LAN"

  condition:
    uint16(0) == 0x5a4d and
    all of them
}