rule TTP_XOR_QUAD_CurrentVersionRun_6ae0 {
  strings:
    $key_6ae0 = { 39 8f [2] 1d 81 [2] 36 ad [2] 18 8f [2] 0c 94 [2] 03 8e [2] 1d 93 [2] 1f 92 [2] 04 94 [2] 18 93 [2] 04 bc }

  condition:
    any of them
}