rule ARKBIRD_SOLG_APT_Oilrig_PSH_Helminth_2016_1: FILE {
  meta:
    description = "Detect Powershell script Helminth in base 64 used by OilRig (2016)"
    author      = "Arkbird_SOLG"
    id          = "782503c2-a292-505c-b513-79cbbd381124"
    date        = "2020-08-26"
    modified    = "2021-07-13"
    reference   = "https://twitter.com/Arkbird_SOLG/status/1298758788028264450"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-26/APT_OilRig_2016.yar#L25-L45"
    license_url = "N/A"
    logic_hash  = "0216015765f5abdb6ccf7643344aead51e4eebb19fd947f9484ce5dc6696d4d5"
    score       = 75
    quality     = 61
    tags        = "FILE"
    hash1       = "1edbb818ea75919bb70bd2496e789e89d26c94cdf65ab61ebb5f1403d45d323c"
    hash2       = "1191d5c1dd7f6ac38b8d72bee37415b3ff1c28a8f907971443ac3a36906e8bf5"

  strings:
    $block1 = "pteWlkID0gJyMjIycgDQogJGdsb2JhbDpteWhvbWUgPSAiJGVudjpQd"
    $block2 = { 41 67 ?? ?? 42 6c 62 48 4e 6c 61 57 59 6f 4a 47 31 35 5a 6d 78 68 5a 7a 4d 67 4c 57 56 78 49 44 49 70 49 41 30 4b 49 43 41 67 49 48 73 67 44 51 6f 67 49 43 41 67 49 43 41 67 49 43 67 6e 64 33 63 6e 4b 79 52 6e 62 47 39 69 59 57 77 36 62 58 6c 70 5a 43 73 6b 59 32 31 6b 61 57 51 72 4a 48 42 68 63 6e 52 70 5a 43 73 6f }
    $block3 = "jaGFyXSBbaW50XSAkdG1wWzBdKSArIC"
    $block4 = "CRjbnQgLWVxIDI1KSkgDQogICAgeyA"
    $block5 = "ZlRE5TICgkZCkgDQp7IA0KCSRjbnQgPSAwIA0KCXdoaWxlICgkY250IC1sdCAyMCkgDQoJeyANCgkJdHJ5IA0KCQl7"
    $block6 = "KICAgICAgICAkaSsrIA0KICAgIH0gDQogICAgaWYoJHJldCAtZXEgMSkgDQogICA"
    $block7 = "w6bXlmbGFnID0gMCANCiAgICB9IA0KICAgIGVsc2VpZiAoJGdsb2JhbDpteWZsYWcgLWVxIDEpIA0KICAgIHsgDQogICAgICAgICR0bXAgPSAkbXlkYXRhLlNwbGl0KCcuJykgDQogICAgICAgIFtTeXN0ZW0uSU8uRmlsZV06OkFwcGVuZEFsbFRleHQoJGdsb2JhbDpteWhvbWUrJ3RwXCcrJGdsb2JhbDpmaWxlbmFt"
    $block8 = { 4a 47 6b 72 4b 79 41 4e 43 69 41 67 49 43 42 39 49 41 30 4b 49 48 30 67 44 51 6f 67 44 51 6f 67 5a 6e 56 75 59 33 52 70 62 32 34 67 52 32 56 30 53 55 [1-10] 4e 43 69 41 67 49 43 41 6b 5a 32 78 76 59 6d 46 73 4f 6d 31 35 61 57 51 67 50 53 42 54 5a 57 35 6b 55 6d 56 6a 5a 57 6c 32 5a 55 52 4f 55 79 41 6f 4b 45 64 6c 64 46 4e 31 59 69 41 77 4b 53 73 6e 4d 7a 41 6e 4b 53 41 4e 43 69 42 39 49 41 30 4b 49 41 30 4b 49 47 5a 31 62 6d 4e 30 61 57 39 [1-10] 56 52 6f 61 58 4e 47 }
    $block9 = "sgDQoJCW1kIC1Gb3JjZSAoJGdsb2JhbDpteWhvbWUrJ3RwXCcpIA0KCQlHZXRJRCANCgkJQ2hhbmdlVGhpc0ZpbGUgJGdsb2JhbDpteWlkIA0KICAgIH0gDQogfSANCiBmdW5jdGlvbiBtYWluIA0K"

  condition:
    filesize < 3KB and 7 of them
}