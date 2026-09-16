rule TTP_XOR_WriteProcessMemory_a16a {
  strings:
    $key_a16a = { f6 18 [2] c4 3a [2] c2 0f [2] ec 0f [2] d3 13 }

  condition:
    any of them
}