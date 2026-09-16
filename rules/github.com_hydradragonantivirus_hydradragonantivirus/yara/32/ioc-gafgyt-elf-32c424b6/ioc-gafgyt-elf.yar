import "hash"
rule IOC_GAFGYT_elf {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_GAFGYT_LAB"
    date_IOC   = "2023-11-14 19:12:25"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "GAFGYT"
    file_type  = "elf"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "b6ee6cc4d468044d42a71e0cc4ae1b15a352baa52e84671f8a0e8bba743e8788" or
    hash.sha256(0, filesize) == "2b2ec22f0dd019563b5ca08f2956b78a72fe009c86dd581885b11a8feedf5bc9" or
    hash.sha256(0, filesize) == "5ae7b28dbd86a21f6686e0db77f06536e9a090569e78b0d60e9c924dacc3b7e2" or
    hash.sha256(0, filesize) == "41382ba72b27d90f0c8e72293cccce520751d1b87a841e72be95f558b0bea002" or
    hash.sha256(0, filesize) == "7f571631dc5974149b8f7165b999f09f179e5674260b173fe0bbc38e221a8e88" or
    hash.sha256(0, filesize) == "e85426f6c3244bdf96fde023e7e2d25d88b061a7ae622203427247068af067cb" or
    hash.sha256(0, filesize) == "e1a6bd6f51a9fcae5e8fccc41554f19c431b1418dec4964947c18d643a1bcdef" or
    hash.sha256(0, filesize) == "34254e7c3ec86e864cfc6f88a62bb25187cddefcfaaa6079926ef374fdb74b5e" or
    hash.sha256(0, filesize) == "4a74258dd1dd503a07111074382b11f791c03e94dddc06d04680ae0d61f98de6" or
    hash.sha256(0, filesize) == "74426a4c85dc167e3d82b2f405d9a9ab6b9e2cf4c7ee93fce8a9a0a5fd21c823" or
    hash.sha256(0, filesize) == "83981024c834aacc141729a185cc3f3771e04feb8632ea209d47909e3b82d4b1" or
    hash.sha256(0, filesize) == "d511c100966b936df679e667e2cc18bd4bdef37c2d65ddd5ff32932b4815309c" or
    hash.sha256(0, filesize) == "53d5d833fb1e0b2df11b1c33e696fb490576d1a54b9d509eafe19afa9ee67912" or
    hash.sha256(0, filesize) == "3c7dfa7bd2bd84da4d5be3357806bbc792428bb82a5acb0f350c01affd1a7a8f" or
    hash.sha256(0, filesize) == "e827b2fa3363a526db964ea77b13a38edf35996619f1bf5bf5e5ecc6179b4989" or
    hash.sha256(0, filesize) == "eac009df353d224b3a564310e10e1aea77e0cb8806e56ec0c8dbe84a3af4747e" or
    hash.sha256(0, filesize) == "96041a9b535707f03ead8059db28c2fd76247794c2020eba53e09e52c2e45bb6" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}