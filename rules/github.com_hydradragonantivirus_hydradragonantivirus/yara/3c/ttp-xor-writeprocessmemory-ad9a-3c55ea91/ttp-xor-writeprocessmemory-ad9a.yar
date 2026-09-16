rule TTP_XOR_WriteProcessMemory_ad9a {
  strings:
    $key_ad9a = { fa e8 [2] c8 ca [2] ce ff [2] e0 ff [2] df e3 }

  condition:
    any of them
}