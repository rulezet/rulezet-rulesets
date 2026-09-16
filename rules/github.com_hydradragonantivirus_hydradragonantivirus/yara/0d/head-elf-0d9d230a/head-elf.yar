rule head_elf {
  condition:
    uint32be(0) == 0x7f454c46
}