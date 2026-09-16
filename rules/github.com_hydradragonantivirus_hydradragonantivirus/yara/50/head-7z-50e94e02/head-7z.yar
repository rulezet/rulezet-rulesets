rule head_7z {
  condition:
    uint16be(0) == 0x377a
}