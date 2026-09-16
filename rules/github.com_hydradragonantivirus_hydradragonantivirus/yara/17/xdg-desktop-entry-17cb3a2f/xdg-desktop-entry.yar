rule xdg_desktop_entry {
  condition:
    uint32(0) == 0x7365445B and uint32(11) == 0x5D797274
}