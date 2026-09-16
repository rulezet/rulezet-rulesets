rule TTP_XOR_QUAD_CurrentVersionRun_6be0 {
  strings:
    $key_6be0 = { 38 8f [2] 1c 81 [2] 37 ad [2] 19 8f [2] 0d 94 [2] 02 8e [2] 1c 93 [2] 1e 92 [2] 05 94 [2] 19 93 [2] 05 bc }

  condition:
    any of them
}