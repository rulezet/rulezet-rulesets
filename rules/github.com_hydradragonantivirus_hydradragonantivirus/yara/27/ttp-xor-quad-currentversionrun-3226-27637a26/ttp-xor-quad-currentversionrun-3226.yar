rule TTP_XOR_QUAD_CurrentVersionRun_3226 {
  strings:
    $key_3226 = { 61 49 [2] 45 47 [2] 6e 6b [2] 40 49 [2] 54 52 [2] 5b 48 [2] 45 55 [2] 47 54 [2] 5c 52 [2] 40 55 [2] 5c 7a }

  condition:
    any of them
}