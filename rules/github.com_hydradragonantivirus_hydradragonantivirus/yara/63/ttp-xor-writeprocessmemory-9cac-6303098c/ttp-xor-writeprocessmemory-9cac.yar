rule TTP_XOR_WriteProcessMemory_9cac {
  strings:
    $key_9cac = { cb de [2] f9 fc [2] ff c9 [2] d1 c9 [2] ee d5 }

  condition:
    any of them
}