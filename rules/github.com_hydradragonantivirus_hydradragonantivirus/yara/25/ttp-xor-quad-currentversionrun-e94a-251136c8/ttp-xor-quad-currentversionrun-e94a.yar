rule TTP_XOR_QUAD_CurrentVersionRun_e94a {
  strings:
    $key_e94a = { ba 25 [2] 9e 2b [2] b5 07 [2] 9b 25 [2] 8f 3e [2] 80 24 [2] 9e 39 [2] 9c 38 [2] 87 3e [2] 9b 39 [2] 87 16 }

  condition:
    any of them
}