rule TTP_XOR_WriteProcessMemory_9e54 {
  strings:
    $key_9e54 = { c9 26 [2] fb 04 [2] fd 31 [2] d3 31 [2] ec 2d }

  condition:
    any of them
}