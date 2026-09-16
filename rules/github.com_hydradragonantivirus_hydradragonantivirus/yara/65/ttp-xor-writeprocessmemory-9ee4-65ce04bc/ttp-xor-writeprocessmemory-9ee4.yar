rule TTP_XOR_WriteProcessMemory_9ee4 {
  strings:
    $key_9ee4 = { c9 96 [2] fb b4 [2] fd 81 [2] d3 81 [2] ec 9d }

  condition:
    any of them
}