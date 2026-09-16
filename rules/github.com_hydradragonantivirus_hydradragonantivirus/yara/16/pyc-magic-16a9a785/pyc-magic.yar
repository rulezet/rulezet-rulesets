rule pyc_magic {
  
  condition:
    uint16(2) == 0x0a0d
}