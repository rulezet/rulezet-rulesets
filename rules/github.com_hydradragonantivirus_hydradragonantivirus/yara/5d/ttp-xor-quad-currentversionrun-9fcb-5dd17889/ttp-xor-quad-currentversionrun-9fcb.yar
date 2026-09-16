rule TTP_XOR_QUAD_CurrentVersionRun_9fcb {
  strings:
    $key_9fcb = { cc a4 [2] e8 aa [2] c3 86 [2] ed a4 [2] f9 bf [2] f6 a5 [2] e8 b8 [2] ea b9 [2] f1 bf [2] ed b8 [2] f1 97 }

  condition:
    any of them
}