rule TTP_XOR_QUAD_CurrentVersionRun_2ee0 {
  strings:
    $key_2ee0 = { 7d 8f [2] 59 81 [2] 72 ad [2] 5c 8f [2] 48 94 [2] 47 8e [2] 59 93 [2] 5b 92 [2] 40 94 [2] 5c 93 [2] 40 bc }

  condition:
    any of them
}