rule infected_05_29_18_case109_case109_scanner {
  meta:
    description = "case109 - file scanner.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "35bbe0242fbd1ea511e7272d43d8351a9a0033551a204cc612776571cf159651"

  strings:
    $s1 = "// Scanconfig 4.0 - www.code-security.com" fullword ascii
    $s2 = "// Author : uzanc | uzanc@live.com" fullword ascii
        $s4 = "eval(base64_decode($scanconfig))" fullword ascii
    $s5 = "// Thanks for : Hacker Cisadane - Lumajangcrew - TMTC 2 - Devilzc0de - Hacker Newbie - Indonesian Cyber - Indonesian Hacker - In" ascii
    $s6 = "// Thanks for : Hacker Cisadane - Lumajangcrew - TMTC 2 - Devilzc0de - Hacker Newbie - Indonesian Cyber - Indonesian Hacker - In" ascii
    $s7 = "evilgirl | blackboy007 | dopunk | l1n9g4 | spykit | and you" fullword ascii
    $s8 = "// Supporter by : cakill | xadpritox | dansky | arulz | direxer | jhoni | guard | nacomb13 | nobita_chupuy | mr.at | zerocool | " ascii
  
  condition:
    all of them
}