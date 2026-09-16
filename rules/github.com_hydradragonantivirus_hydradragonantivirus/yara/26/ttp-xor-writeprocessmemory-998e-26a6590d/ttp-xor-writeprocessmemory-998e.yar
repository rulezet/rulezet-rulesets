rule TTP_XOR_WriteProcessMemory_998e {
  strings:
    $key_998e = { ce fc [2] fc de [2] fa eb [2] d4 eb [2] eb f7 }

  condition:
    any of them
}