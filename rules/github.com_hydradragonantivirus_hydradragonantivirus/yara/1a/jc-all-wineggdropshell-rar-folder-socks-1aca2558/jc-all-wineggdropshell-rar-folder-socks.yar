rule Jc_ALL_WinEggDropShell_rar_Folder_SOCKS {
  meta:
    description = "Disclosed hacktool set (old stuff) - file SOCKS.exe"
    author      = "Florian Roth"
    date        = "23.11.14"
    score       = 60
    hash        = "ad2168e9837592eeb120fc6798648b2fe996f79c"

  strings:
    $s0 = "http://go.163.com/~sdemo" fullword ascii
    $s1 = "http://go.163.com/sdemo" fullword wide
    $s4 = "Player.EXE" fullword wide
    $s5 = "mailto:sdemo@263.net" fullword ascii
    $s6 = "S-Player.exe" fullword ascii

  condition:
    all of them
}