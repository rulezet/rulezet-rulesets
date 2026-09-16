rule TTP_XOR_WriteProcessMemory_9edc {
  strings:
    $key_9edc = { c9 ae [2] fb 8c [2] fd b9 [2] d3 b9 [2] ec a5 }

  condition:
    any of them
}