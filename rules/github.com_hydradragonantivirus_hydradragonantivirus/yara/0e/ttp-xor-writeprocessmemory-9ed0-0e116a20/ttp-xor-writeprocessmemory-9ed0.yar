rule TTP_XOR_WriteProcessMemory_9ed0 {
  strings:
    $key_9ed0 = { c9 a2 [2] fb 80 [2] fd b5 [2] d3 b5 [2] ec a9 }

  condition:
    any of them
}