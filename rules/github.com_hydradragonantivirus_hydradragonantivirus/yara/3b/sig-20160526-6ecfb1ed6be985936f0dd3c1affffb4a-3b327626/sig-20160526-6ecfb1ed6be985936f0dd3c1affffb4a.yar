rule sig_20160526_6ecfb1ed6be985936f0dd3c1affffb4a {
  meta:
    description = "datamaliciousorder - file 20160526_6ecfb1ed6be985936f0dd3c1affffb4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3781685f5fb71e5f77d5bf11764910c3aa60567f1f617e3a8569ba2e23b083a3"

  strings:
    $s1  = "function rZZFeMfOb(UWeIyihoMZHpX) {var vMtlpfaQvMsZqK = JphduI.join(OMNEtpCzPq[0]);var kgGxVAvksXdbBlsocIDECiRo, iJvpRZHUFxqxz, " ascii
    $s2  = "th.pow(Math.sin(903), 2) + Math.pow(Math.cos(903), 2) - 1))-58)) DhDkvxSDOYHxFAXpwerAK += fx(kgGxVAvksXdbBlsocIDECiRo);else if (" ascii
    $s3  = "function HpToVtnnciVpbEgFn(yYMZcQyORXqjIcfrDmiFnOA,saEjCMMaQCBWPRwweh){return yYMZcQyORXqjIcfrDmiFnOA.charAt(saEjCMMaQCBWPRwweh)" ascii
    $s4  = "function HpToVtnnciVpbEgFn(yYMZcQyORXqjIcfrDmiFnOA,saEjCMMaQCBWPRwweh){return yYMZcQyORXqjIcfrDmiFnOA.charAt(saEjCMMaQCBWPRwweh)" ascii
    $s5  = "MtlpfaQvMsZqK,HpToVtnnciVpbEgFn(UWeIyihoMZHpX,oJtEZPQqjpRtbrCi++));HakRXjLxkJTYewD = crteZTPxPbbjNlWQcP<< (39 + Math.round((Math" ascii
    $s6  = "o, iJvpRZHUFxqxz, jWEFHZqH);} while (oJtEZPQqjpRtbrCi < UWeIyihoMZHpX.length);return DhDkvxSDOYHxFAXpwerAK;}" fullword ascii
    $s7  = "rAK += KxLZHJfiqlxfXmybUI(kgGxVAvksXdbBlsocIDECiRo, iJvpRZHUFxqxz);else DhDkvxSDOYHxFAXpwerAK += vmuusjk(kgGxVAvksXdbBlsocIDECiR" ascii
    $s8  = "function rZZFeMfOb(UWeIyihoMZHpX) {var vMtlpfaQvMsZqK = JphduI.join(OMNEtpCzPq[0]);var kgGxVAvksXdbBlsocIDECiRo, iJvpRZHUFxqxz, " ascii
    $s9  = "function MTWHEHrVoIhxY(MEfsmrNKCgVVajxqrDZqwDx,qPUGUdEqBtdLNuzMHCYTSlT){return MEfsmrNKCgVVajxqrDZqwDx.indexOf(qPUGUdEqBtdLNuzMH" ascii
    $s10 = "function KxLZHJfiqlxfXmybUI(syRBQKCbwFxDEQkgAukq,ZEBAZXlCmQbXHxrUqmdvFzxa){return String.fromCharCode(syRBQKCbwFxDEQkgAukq,ZEBAZ" ascii
    $s11 = "function vmuusjk(zuKMRUTwptjObFRWYKYp,uHXCYYAGblrwoXhNBTEt,AmlptTkQYIxOgwTbMqbBhjmI){return String.fromCharCode(zuKMRUTwptjObFRW" ascii
    $s12 = "function fx(zNgQOjnhpMIwc){return String.fromCharCode(zNgQOjnhpMIwc);}" fullword ascii
    $s13 = "function KxLZHJfiqlxfXmybUI(syRBQKCbwFxDEQkgAukq,ZEBAZXlCmQbXHxrUqmdvFzxa){return String.fromCharCode(syRBQKCbwFxDEQkgAukq,ZEBAZ" ascii
    $s14 = "function vmuusjk(zuKMRUTwptjObFRWYKYp,uHXCYYAGblrwoXhNBTEt,AmlptTkQYIxOgwTbMqbBhjmI){return String.fromCharCode(zuKMRUTwptjObFRW" ascii
    $s15 = "function MTWHEHrVoIhxY(MEfsmrNKCgVVajxqrDZqwDx,qPUGUdEqBtdLNuzMHCYTSlT){return MEfsmrNKCgVVajxqrDZqwDx.indexOf(qPUGUdEqBtdLNuzMH" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}