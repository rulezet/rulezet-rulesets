import "pe"
rule hancitor_packed {
  meta:
    description = "Hancitor (packed)"
    author = "Andras Gemes"
    date = "2025-02-18"
    sha256 = "efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8"
    ref1 = "https://shadowshell.io/hancitor-loader"
    ref2 = "https://bazaar.abuse.ch/sample/efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8"

  strings:
    
    $1 = "Broke"
    $2 = "Necessaryearly"

    
    $_memcpy = { 68 88 0e 00 00 68 [4] 68 [4] e8 }

    
    $GetSystemDirectoryW = { 68 83 05 00 00 8d 54 24 34 52 ff 15 }

    
    $GetModuleFileNameW = { 68 83 05 00 00 68 [4] 6a 00 ff 15 }

    
    $VirtualProtectEx = { a1 [4] 8b 15 [4] 68 [4] 6a 40 68 00 51 00 00 50 6a ff 8d 9c 16 0f 01 00 00 ff 15 }

    
    $GetCurrentDirectoryW = { 2a c2 68 [4] 02 c3 68 83 05 00 00 a2 [4] ff 15 }

    
    $decrypt1 = { 8a da 2a d8 02 d9 80 c3 19 0f b6 cb 2b ca 0f b7 d6 03 d1 89 15 }

    
    $decrypt2 = { 8b 1d [4] 81 c7 d0 64 08 01 8a cb 2a c8 89 7d 00 80 c1 17 83 c5 04 83 6c 24 10 01 89 3d }

  condition:
    pe.is_pe and 5 of them
}