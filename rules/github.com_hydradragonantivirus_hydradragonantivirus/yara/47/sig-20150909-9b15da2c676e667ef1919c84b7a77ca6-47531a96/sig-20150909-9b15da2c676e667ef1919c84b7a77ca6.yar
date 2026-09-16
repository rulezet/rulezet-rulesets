rule sig_20150909_9b15da2c676e667ef1919c84b7a77ca6 {
  meta:
    description = "datamaliciousorder - file 20150909_9b15da2c676e667ef1919c84b7a77ca6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99b5f47ff24405293263799dce078014694d449eacdee05207e8f8b357b6bcfb"

  strings:
    $x1  = "var kStageSizeDidChangeEvent=\"DisplayManager:StageSizeDidChangeEvent\";var kTimeoutValueForCursor=1000;var kMobilePortraitModeH" ascii
    $s2  = "onDidChangeEvent.bind(this));this.body=document.getElementById(\"body\");this.stageArea=document.getElementById(\"stageArea\");t" ascii
    $s3  = "/b><br><b>Texture Loader:</b><br>- Num Load Requests: <b>\"+(c>0?(\"<span style='color:yellow;'>\"+c+\"</span>\"):\"0\")+\"</b><" ascii
    $s4  = "owAll_partTwo:function(){if(gDevice===kDeviceMobile){window.scrollTo(0,1);setTimeout(this.showAll_partThree.bind(this))}else{thi" ascii
    $s5  = "0px;'><b>Degrade Statistics:</b><br>- Scenes w/Degrades: <b>\"+a.numDegradedSlides+\"</b><br>- Total Textures Degraded: <b>\"+a." ascii
    $s6  = "ht=window.innerHeight}},clearLaunchMode:function(){this.inLaunchMode=false;var a=this;runInNextEventLoop(this.showAll.bind(this)" ascii
    $s7  = "Move.bind(this));this.lastMouseX=-1;this.lastMouseY=-1;this.cursorTimeout=null;this.setTimeoutForCursor()}},setHyperlinksOnlyMod" ascii
    $s8  = "0;h=0;if(gIpad){b=kiPadDeviceHeight}else{b=kiPhoneDeviceHeight}e=b}if(p!=-1&&h!=-1&&e!=-1&&b!=-1){var s=document.getElementById(" ascii
    $s9  = "leDisplayWidth-this.stageAreaWidth-n.width,height:this.stageAreaHeight};var l=document.getElementById(\"statisticsDisplay\");if(" ascii
    $s10 = "ition: absolute; left: 175px;'><b>Scene Statistics:</b><br>- Scene Index: <b>\"+gShowController.currentSceneIndex+\"</b><br>- Te" ascii
    $s11 = ">- Over Pixel Limit Now: <b>\"+(g?\"<span style='color:red;'>YES</span>\":\"NO\")+\"</b><br>- Ever Over Pixel Limit: <b>\"+(this" ascii
    $s12 = "ures: <b>\"+h.numTextures+\"</b><br>- Total Pixels: <b>\"+h.numPixels+\" MP</b><br>- Peak Pixels: <b>\"+this.stageHighWaterMark+" ascii
    $s13 = "<br>- Scenes: <b>\"+j.numScenes+\"</b><br>- Textures: <b>\"+j.numTextures+\"</b><br>- Pixels: <b>\"+j.numPixels+\" MP</b><br>- P" ascii
    $s14 = "DegradedTextures+\"</b><br>- Max Textures/Scene: <b>\"+a.maxNumDegradedTexturesPerSlide+\"</b><br>- Textures in Current: <b>\"+(" ascii
    $s15 = "his.nextButton);showElement(this.slideCounter);showElement(this.helpText);showElement(this.infoPanelIcon)}else{hideElement(this." ascii
    $s16 = "howWidth;k=k}}}else{if(gIpad===false){if(this.orientation===kOrientationPortrait){q=this.usableDisplayWidth-2*kMobilePortraitMod" ascii
    $s17 = "izeTimer=setTimeout(this.handleOrientationDidChangeEvent_partTwo.bind(this),300)},handleOrientationDidChangeEvent_partTwo:functi" ascii
    $s18 = "display=\"none\"},handleMouseMove:function(a){a=a||window.event;var b=Math.abs(this.lastMouseX-a.clientX)+Math.abs(this.lastMous" ascii
    $s19 = ";hideElement(this.infoPanelIcon)}else{if(this.orientation===kOrientationPortrait){showElement(this.previousButton);showElement(t" ascii
    $s20 = "Timeout)}this.cursorTimeout=setTimeout(this.handleTimeoutForCursor.bind(this),kTimeoutValueForCursor)},clearTimeoutForCursor:fun" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}