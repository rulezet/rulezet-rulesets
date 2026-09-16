rule TTP_XOR_QUAD_CurrentVersionRun_73ff {
  strings:
    $key_73ff = { 20 90 [2] 04 9e [2] 2f b2 [2] 01 90 [2] 15 8b [2] 1a 91 [2] 04 8c [2] 06 8d [2] 1d 8b [2] 01 8c [2] 1d a3 }

  condition:
    any of them
}