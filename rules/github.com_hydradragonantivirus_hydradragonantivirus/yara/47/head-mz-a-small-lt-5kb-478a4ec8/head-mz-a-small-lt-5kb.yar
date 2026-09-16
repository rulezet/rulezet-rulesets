rule head_mz_a_small_lt_5kb {
  condition:
    uint16be(0) == 0x4d5a
    and filesize < 5KB
}