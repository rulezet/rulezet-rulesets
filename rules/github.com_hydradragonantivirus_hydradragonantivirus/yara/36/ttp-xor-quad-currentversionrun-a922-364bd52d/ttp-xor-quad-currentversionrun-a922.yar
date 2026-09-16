rule TTP_XOR_QUAD_CurrentVersionRun_a922 {
  strings:
    $key_a922 = { fa 4d [2] de 43 [2] f5 6f [2] db 4d [2] cf 56 [2] c0 4c [2] de 51 [2] dc 50 [2] c7 56 [2] db 51 [2] c7 7e }

  condition:
    any of them
}