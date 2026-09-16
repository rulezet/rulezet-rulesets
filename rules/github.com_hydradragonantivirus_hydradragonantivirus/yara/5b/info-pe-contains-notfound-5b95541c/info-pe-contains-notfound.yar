rule INFO_PE_Contains_NotFound {
  strings:
    $ = "not found.<" nocase ascii wide

  condition:
    uint16be(0) == 0x4d5a and all of them
}