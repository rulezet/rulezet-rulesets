rule TTP_XOR_QUAD_CurrentVersionRun_f9ba {
  strings:
    $key_f9ba = { aa d5 [2] 8e db [2] a5 f7 [2] 8b d5 [2] 9f ce [2] 90 d4 [2] 8e c9 [2] 8c c8 [2] 97 ce [2] 8b c9 [2] 97 e6 }

  condition:
    any of them
}