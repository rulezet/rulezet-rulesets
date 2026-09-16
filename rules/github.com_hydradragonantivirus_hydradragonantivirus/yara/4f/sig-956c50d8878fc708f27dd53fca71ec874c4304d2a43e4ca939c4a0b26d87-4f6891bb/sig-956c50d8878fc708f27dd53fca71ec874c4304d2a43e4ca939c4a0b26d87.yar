rule sig_956c50d8878fc708f27dd53fca71ec874c4304d2a43e4ca939c4a0b26d87 {
  meta:
    description = "datamaliciousorder - file 956c50d8878fc708f27dd53fca71ec874c4304d2a43e4ca939c4a0b26d87d6f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "956c50d8878fc708f27dd53fca71ec874c4304d2a43e4ca939c4a0b26d87d6f8"

  strings:
    $x1  = "wantingfullmute=[];wantingfullmute['decaychillygrowth']='i';wantingfullmute['regularunclecast']='k';wantingfullmute['notebalance" ascii
    $s2  = "block\"},nt={letterSpacing:\"0\",fontWeight:\"400\"};function rt(e,t,n){var r=Y.exec(t);return r?Math.max(0,r[2]-(n||0))+(r[3]||" ascii
    $s3  = "bal:!0,processData:!0,async:!0,contentType:\"application/x-www-form-urlencoded; charset=UTF-8\",accepts:{\"*\":zt,text:\"text/pl" ascii
    $s4  = "rType:!0,screenX:!0,screenY:!0,targetTouches:!0,toElement:!0,touches:!0,which:!0},ce.event.addProp),ce.each({focus:\"focusin\",b" ascii
    $s5  = ")||h))return T.abort();if(u=\"abort\",b.add(v.complete),T.done(v.success),T.fail(v.error),c=Vt(_t,v,t,T)){if(T.readyState=1,g&&m" ascii
    $s6  = "(this,i)-1)?_.set(this,i,e):(this.removeEventListener(i,o),_.remove(this,i))},_default:function(e){return _.get(e.target,r)},del" ascii
    $s7  = "turn ce.css(e,t,\"\")},u=s(),l=n&&n[3]||(ce.cssNumber[t]?\"\":\"px\"),c=e.nodeType&&(ce.cssNumber[t]||\"px\"!==l&&+u)&&Y.exec(ce" ascii
    $s8  = "[t];\"string\"===(o=typeof n)&&(i=Y.exec(n))&&i[1]&&(n=te(e,t,i),o=\"number\"),null!=n&&n==n&&(\"number\"!==o||u||(n+=i&&i[3]||(" ascii
    $s9  = "r:\"focusout\"},function(r,i){function o(e){if(C.documentMode){var t=_.get(this,\"handle\"),n=ce.event.fix(e);n.type=\"focusin\"" ascii
    $s10 = "T,v]),--ce.active||ce.event.trigger(\"ajaxStop\")))}return T},getJSON:function(e,t,n){return ce.get(e,t,n,\"json\")},getScript:f" ascii
    $s11 = "ion(e,t){return ce.get(e,void 0,t,\"script\")}}),ce.each([\"get\",\"post\"],function(e,i){ce[i]=function(e,t,n,r){return v(t)&&(" ascii
    $s12 = "event.special[r]={setup:function(){var e;if(He(this,r,!0),!C.documentMode)return!1;(e=_.get(this,i))||this.addEventListener(i,o)" ascii
    $s13 = "unction(e,t,n){var r,i;if(e&&e.preventDefault&&e.handleObj)return r=e.handleObj,ce(e.delegateTarget).off(r.namespace?r.origType+" ascii
    $s14 = "html:\"text/html\",xml:\"application/xml, text/xml\",json:\"application/json, text/javascript\"},contents:{xml:/\\bxml\\b/,html:" ascii
    $s15 = "){if(11!==p&&(u=L.exec(t)))if(i=u[1]){if(9===p){if(!(a=e.getElementById(i)))return n;if(a.id===i)return k.call(n,a),n}else if(f&" ascii
    $s16 = "ype?\"focus\":\"blur\",n.isSimulated=!0,t(e),n.target===n.currentTarget&&t(n)}else ce.event.simulate(i,e.target,ce.event.fix(e))" ascii
    $s17 = "._evalUrl(u.src,{nonce:u.nonce||u.getAttribute(\"nonce\")},l):m(u.textContent.replace(Me,\"\"),u,l))}return n}function Be(e,t,n)" ascii
    $s18 = "rget.parentNode:e.target,this.currentTarget=e.currentTarget,this.relatedTarget=e.relatedTarget):this.type=e,t&&ce.extend(this,t)" ascii
    $s19 = "eturn ce.ajax({url:e,type:\"GET\",dataType:\"script\",cache:!0,async:!1,global:!1,converters:{\"text script\":function(){}},data" ascii
    $s20 = "while(a){for(o in n&&!(r=y.exec(a))||(r&&(a=a.slice(r[0].length)||a),s.push(i=[])),n=!1,(r=m.exec(a))&&(n=r.shift(),i.push({valu" ascii

  condition:
    uint16(0) == 0x2a2f and
    1 of ($x*) and 4 of them
}