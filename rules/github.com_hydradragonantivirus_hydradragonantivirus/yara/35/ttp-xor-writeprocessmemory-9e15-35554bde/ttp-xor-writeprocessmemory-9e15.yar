rule TTP_XOR_WriteProcessMemory_9e15 {
  strings:
    $key_9e15 = { c9 67 [2] fb 45 [2] fd 70 [2] d3 70 [2] ec 6c }

  condition:
    any of them
}