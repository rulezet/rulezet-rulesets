rule TTP_XOR_QUAD_CurrentVersionRun_a930 {
  strings:
    $key_a930 = { fa 5f [2] de 51 [2] f5 7d [2] db 5f [2] cf 44 [2] c0 5e [2] de 43 [2] dc 42 [2] c7 44 [2] db 43 [2] c7 6c }

  condition:
    any of them
}