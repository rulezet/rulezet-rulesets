rule TTP_XOR_WriteProcessMemory_9eaf {
  strings:
    $key_9eaf = { c9 dd [2] fb ff [2] fd ca [2] d3 ca [2] ec d6 }

  condition:
    any of them
}