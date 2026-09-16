rule TTP_XOR_WriteProcessMemory_ae8e {
  strings:
    $key_ae8e = { f9 fc [2] cb de [2] cd eb [2] e3 eb [2] dc f7 }

  condition:
    any of them
}