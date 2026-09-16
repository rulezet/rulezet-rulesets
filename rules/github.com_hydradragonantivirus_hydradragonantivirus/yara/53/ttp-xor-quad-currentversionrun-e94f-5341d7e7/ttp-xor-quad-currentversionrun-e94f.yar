rule TTP_XOR_QUAD_CurrentVersionRun_e94f {
  strings:
    $key_e94f = { ba 20 [2] 9e 2e [2] b5 02 [2] 9b 20 [2] 8f 3b [2] 80 21 [2] 9e 3c [2] 9c 3d [2] 87 3b [2] 9b 3c [2] 87 13 }

  condition:
    any of them
}