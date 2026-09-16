rule TTP_XOR_QUAD_CurrentVersionRun_1721 {
  strings:
    $key_1721 = { 44 4e [2] 60 40 [2] 4b 6c [2] 65 4e [2] 71 55 [2] 7e 4f [2] 60 52 [2] 62 53 [2] 79 55 [2] 65 52 [2] 79 7d }

  condition:
    any of them
}