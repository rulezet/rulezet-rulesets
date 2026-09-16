rule head_mz_b_small_5kb_10kb {
  condition:
    uint16be(0) == 0x4d5a
    and filesize > 5KB and filesize < 10KB
}