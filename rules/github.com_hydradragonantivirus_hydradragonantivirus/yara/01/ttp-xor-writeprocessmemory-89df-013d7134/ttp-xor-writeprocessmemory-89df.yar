rule TTP_XOR_WriteProcessMemory_89df {
  strings:
    $key_89df = { de ad [2] ec 8f [2] ea ba [2] c4 ba [2] fb a6 }

  condition:
    any of them
}