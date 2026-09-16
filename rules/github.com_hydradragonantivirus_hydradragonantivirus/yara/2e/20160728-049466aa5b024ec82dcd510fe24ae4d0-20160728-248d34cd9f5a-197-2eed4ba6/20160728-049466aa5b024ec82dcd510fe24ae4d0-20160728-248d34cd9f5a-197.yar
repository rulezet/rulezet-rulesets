rule _20160728_049466aa5b024ec82dcd510fe24ae4d0_20160728_248d34cd9f5a_197 {
  meta:
    description = "datamaliciousorder - from files 20160728_049466aa5b024ec82dcd510fe24ae4d0.js, 20160728_248d34cd9f5a5f76b5819c409bd8f61c.js, 20160728_3eb47ccb2350f03abc7aaa17fc10c765.js, 20160728_42a1d5bb96c69f4314f6a8463fba69dc.js, 20160728_4bf4572a9960386e70f3e11376d63551.js, 20160728_6314387c9c0c1aa7f45f8ec08c33ae65.js, 20160728_6368170337f8999a5b5f28f23e5961e8.js, 20160728_7d8f3bf548dc009d8d634c2dd0282687.js, 20160728_85e1e3eb15fe0d9f8926b4fb6b2ca4b4.js, 20160728_899555e23f9c512d5d74471f0482ebcb.js, 20160728_9e1a288a46f328e676c43715e33448f6.js, 20160728_a8931bd9abcae3a2f082abb66c1cc621.js, 20160728_a9c7289f8175e6f1606e6d4be706925e.js, 20160728_df23a8e2ee11572f33fb42512c4ba6c5.js, 20160728_e41ec529f373dcd803a01a633b6af217.js, 20160728_e9c8d86bb7e71c99ff6ebd360b47ad5e.js, 20160728_ebbe2f86820d02ac31f5106fd40e8687.js, 20160728_ec8659e85c371f711c7144c51a7245c6.js, 20160728_f4f00f4fdf53414a1092df4fdc8996da.js, 20160728_faf9d053d47083e3e39787a9d94cfa6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ecb8f262ef8f84fac6dd5ce538b7d48b05fb3c61c73345f0230c09e8568b2d0"
    hash2       = "b336f6b0b58776aba6eb10bf095498eabc735c8a781b42f848717fb4321c1c3a"
    hash3       = "0d92ca1e0fdac97b1df451fdb72577bbd96cf0cd04223db694ea1b9315430b43"
    hash4       = "8d42dc33d06fd54a898cfa26371f34f38922a81b9d6719131dd41060bb1ad975"
    hash5       = "c270d43c86661daf1b7dc5705f1c3dec1c2c4511fbcc4e5b52d00cab07d1055b"
    hash6       = "b2ece79f4479003bb3050ec9ff914de17dab81b06014661e12fa721531671812"
    hash7       = "e3ad97a300425ea917df5ec25ffd7b58d2d34eca3c46a87e111592d914101e0b"
    hash8       = "eb7ad80b7ecede621f8c40c927768e62d1a60e4ff8c0b847ce3d8e6aeeebe8c5"
    hash9       = "67988f85b616aeb42477a8b58b1e091e858fa775ce3ca46f0bf434e339f19672"
    hash10      = "c772b7b711d463d895767816f43256ef4b6665ba29671415164b070e6897cb70"
    hash11      = "061f48680273d327a09b0abebeab69f805604b4b80c2a9733bfff76e7093e579"
    hash12      = "d5369e9f1686d527cc1067a80c556059a1f37a8f3d4fb90aa24c4090a59c302a"
    hash13      = "3019db2d3152731ce2b01669531bd8c71b17b8289df0abf1da7ed372b49b3840"
    hash14      = "da5278df488e5c48e7d9b1a14e23730cfd56d7c03ccba97a7874ce9369ed4b9b"
    hash15      = "d76eb358049923570b50fd18513489d5097a2ff95f64ef757759f0051f27b765"
    hash16      = "2f8bf25689c02733775a1b9a4b769f215c055dc54c800f22ba068be5cab45980"
    hash17      = "e5efea70eb8972b78200fe8ed6d10161e8ebc224f9264f3b67b10879f8446b79"
    hash18      = "5f43670aceff2248dd2bc3a058c57a9482ba48aa4ca7337710f81639233e53e8"
    hash19      = "8fa9e6db63a58bd69656d79bf661569db34d207f6be4313591974b7b6d14d35f"
    hash20      = "420a8de39a357ce5535915a01ea00f4b0bc5b6dd5e3cb447e9b90df14674521d"

  strings:
    $s1  = " thisisaugustcoming_Tetromino.prototype.getNew = function (index) { this.x = 4; index = 6; this.index = index; switch (index) { " ascii
    $s2  = " thisisaugustcoming_Tetromino.prototype.getNew = function (index) { this.x = 4; index = 6; this.index = index; switch (index) { " ascii
    $s3  = ".sprite = 6; this.frameNumber = 4; this.frame = new Array( new Array( new Array(-1, -1), new Array(-1, 0), new Array(0, 0), new " ascii
    $s4  = "rite = 7; this.sprite = 3; this.frame = new Array( new Array( new Array(1, -1), new Array(0, -1), new Array(0, 0), new Array(-1," ascii
    $s5  = "String.prototype.thisisaugustcoming_center2 = function () {" fullword ascii
    $s6  = "thisisaugustcoming_Tetromino.prototype.nextFrame = function () {" fullword ascii
    $s7  = "if ((!thisisaugustcoming_check || !object[thisisaugustcoming_property]) && typeof object.prototype[thisisaugustcoming_property] " ascii
    $s8  = "    return new thisisaugustcoming_rodmands(thisisaugustcoming_param1.x - thisisaugustcoming_param2.x, thisisaugustcoming_param1." ascii
    $s9  = "if ((!thisisaugustcoming_check || !object[thisisaugustcoming_property]) && typeof object.prototype[thisisaugustcoming_property] " ascii
    $s10 = "String.prototype.thisisaugustcoming_shifrator = function() {" fullword ascii
    $s11 = "    return new thisisaugustcoming_rodmands(thisisaugustcoming_param1.x - thisisaugustcoming_param2.x, thisisaugustcoming_param1." ascii
    $s12 = "        } while (thisisaugustcoming_i < thisisaugustcoming_len && thisisaugustcoming_c1 == -1);" fullword ascii
    $s13 = "        } while (thisisaugustcoming_i < thisisaugustcoming_len && thisisaugustcoming_c3 == -1);" fullword ascii
    $s14 = "} catch (thisisaugustcoming_RFXuYwO) {WScript.echo(thisisaugustcoming_RFXuYwO.message);" fullword ascii
    $s15 = "        } while (thisisaugustcoming_i < thisisaugustcoming_len && thisisaugustcoming_c4 == -1);" fullword ascii
    $s16 = "Array(-1, 0) ), new Array( new Array(-1, 0), new Array(0, 0), new Array(1, 0), new Array(0, 1) ), new Array( new Array(0, -1), n" ascii
    $s17 = "ew Array(0, -1), new Array(0, 0), new Array(0, 1) ), new Array( new Array(-1, 0), new Array(0, 0), new Array(1, 0), new Array(-1" ascii
    $s18 = "new Array(0, -1), new Array(0, 0), new Array(1, 0) ), new Array( new Array(0, 0), new Array(1, 0), new Array(0, 1), new Array(1," ascii
    $s19 = " = new Array( new Array( new Array(-1, 0), new Array(0, 0), new Array(1, 0), new Array(1, -1) ), new Array( new Array(-1, -1), n" ascii
    $s20 = " 0) ), new Array( new Array(0, -1), new Array(0, 0), new Array(1, 0), new Array(1, 1) ), new Array( new Array(1, -1), new Array(" ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}