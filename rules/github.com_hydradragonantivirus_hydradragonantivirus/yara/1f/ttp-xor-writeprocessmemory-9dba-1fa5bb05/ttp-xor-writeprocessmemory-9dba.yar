rule TTP_XOR_WriteProcessMemory_9dba {
  strings:
    $key_9dba = { ca c8 [2] f8 ea [2] fe df [2] d0 df [2] ef c3 }

  condition:
    any of them
}