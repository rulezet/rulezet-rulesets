rule TTP_XOR_WriteProcessMemory_9e37 {
  strings:
    $key_9e37 = { c9 45 [2] fb 67 [2] fd 52 [2] d3 52 [2] ec 4e }

  condition:
    any of them
}