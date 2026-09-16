rule TTP_XOR_WriteProcessMemory_9ebf {
  strings:
    $key_9ebf = { c9 cd [2] fb ef [2] fd da [2] d3 da [2] ec c6 }

  condition:
    any of them
}