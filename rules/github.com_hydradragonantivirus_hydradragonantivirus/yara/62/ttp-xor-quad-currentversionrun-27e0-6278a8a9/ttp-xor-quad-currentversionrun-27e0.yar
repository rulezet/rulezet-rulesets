rule TTP_XOR_QUAD_CurrentVersionRun_27e0 {
  strings:
    $key_27e0 = { 74 8f [2] 50 81 [2] 7b ad [2] 55 8f [2] 41 94 [2] 4e 8e [2] 50 93 [2] 52 92 [2] 49 94 [2] 55 93 [2] 49 bc }

  condition:
    any of them
}