rule TTP_XOR_WriteProcessMemory_9e07 {
  strings:
    $key_9e07 = { c9 75 [2] fb 57 [2] fd 62 [2] d3 62 [2] ec 7e }

  condition:
    any of them
}