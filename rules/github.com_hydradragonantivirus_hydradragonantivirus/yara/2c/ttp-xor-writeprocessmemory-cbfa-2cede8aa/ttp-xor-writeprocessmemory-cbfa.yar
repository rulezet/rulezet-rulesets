rule TTP_XOR_WriteProcessMemory_cbfa {
  strings:
    $key_cbfa = { 9c 88 [2] ae aa [2] a8 9f [2] 86 9f [2] b9 83 }

  condition:
    any of them
}