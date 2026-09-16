rule TTP_XOR_WriteProcessMemory_9efd {
  strings:
    $key_9efd = { c9 8f [2] fb ad [2] fd 98 [2] d3 98 [2] ec 84 }

  condition:
    any of them
}