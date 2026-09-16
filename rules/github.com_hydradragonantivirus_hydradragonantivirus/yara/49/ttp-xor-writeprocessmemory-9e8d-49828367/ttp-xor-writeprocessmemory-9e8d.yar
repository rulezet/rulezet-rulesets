rule TTP_XOR_WriteProcessMemory_9e8d {
  strings:
    $key_9e8d = { c9 ff [2] fb dd [2] fd e8 [2] d3 e8 [2] ec f4 }

  condition:
    any of them
}