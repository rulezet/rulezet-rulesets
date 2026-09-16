rule TTP_XOR_WriteProcessMemory_9ec9 {
  strings:
    $key_9ec9 = { c9 bb [2] fb 99 [2] fd ac [2] d3 ac [2] ec b0 }

  condition:
    any of them
}