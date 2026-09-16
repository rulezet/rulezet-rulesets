rule TTP_XOR_WriteProcessMemory_9e01 {
  strings:
    $key_9e01 = { c9 73 [2] fb 51 [2] fd 64 [2] d3 64 [2] ec 78 }

  condition:
    any of them
}