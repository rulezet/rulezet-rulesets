rule MAL_BRC4_string_obfuscation_bytes {
  meta:
    description   = "Matches hex byte pattern used to obfuscate strings in Brute Ratel (BRC4) samples."
    last_modified = "2024-02-03"
    author        = "@petermstewart"
    DaysofYara    = "34/100"
    sha256        = "3ad53495851bafc48caf6d2227a434ca2e0bef9ab3bd40abfe4ea8f318d37bbe"
    sha256        = "973f573cab683636d9a70b8891263f59e2f02201ffb4dd2e9d7ecbb1521da03e"

  strings:
    $a1 = { 50 48 B8 74 00 20 00 64 00 6F 00 50 48 }      $a2 = { 50 48 B8 6E 00 73 00 68 00 6F 00 50 48 }      $a3 = { 50 48 B8 63 00 72 00 65 00 65 00 50 48 }      $b1 = { 50 48 B8 69 00 6D 00 61 00 67 00 50 48 }      $b2 = { 50 48 B8 32 64 2E 70 6E 67 00 00 50 48 }      $c1 = { 50 48 B8 6E 00 67 00 3A 00 20 00 50 48 }      $c2 = { 50 48 B8 65 00 72 00 79 00 69 00 50 48 }      $c3 = { 50 48 B8 5D 00 20 00 51 00 75 00 50 48 }  
  condition:
    uint16(0) == 0x5a4d and
    5 of them
}