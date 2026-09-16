rule TTP_XOR_WriteProcessMemory_9baf {
  strings:
    $key_9baf = { cc dd [2] fe ff [2] f8 ca [2] d6 ca [2] e9 d6 }

  condition:
    any of them
}