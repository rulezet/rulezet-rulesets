rule TTP_XOR_QUAD_CurrentVersionRun_9412 {
  strings:
    $key_9412 = { c7 7d [2] e3 73 [2] c8 5f [2] e6 7d [2] f2 66 [2] fd 7c [2] e3 61 [2] e1 60 [2] fa 66 [2] e6 61 [2] fa 4e }

  condition:
    any of them
}